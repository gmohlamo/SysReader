#include "../include/readsys.h"

static const SyscallConvention conv_x86_64 = {
    .name = "x86-64",
    .syscall_reg = "rax",
    .alt_syscall_reg = "eax",
    .arg_regs = {"rdi", "rsi", "rdx", "r10", "r8", "r9"}
};

static const SyscallConvention conv_x86_32 = {
    .name = "x86-32",
    .syscall_reg = "eax",
    .alt_syscall_reg = NULL,
    .arg_regs = {"ebx", "ecx", "edx", "esi", "edi", "ebp"}
};

static const SyscallConvention conv_arm64 = {
    .name = "arm64",
    .syscall_reg = "x8",
    .alt_syscall_reg = "w8",
    .arg_regs = {"x0", "x1", "x2", "x3", "x4", "x5"}
};

static const SyscallConvention conv_arm32 = {
    .name = "arm32",
    .syscall_reg = "r7",
    .alt_syscall_reg = NULL,
    .arg_regs = {"r0", "r1", "r2", "r3", "r4", "r5"}
};

const SyscallConvention *get_syscall_convention(RCore *core) {
  if (!core) {
    return &conv_x86_64;
  }

  const char *arch = NULL;
  int bits = 0;

  if (core->bin) {
    RBinInfo *info = r_bin_get_info(core->bin);
    if (info) {
      arch = info->arch;
      bits = info->bits;
    }
  }

  if (!arch || !*arch) {
    arch = r_config_get(core->config, "asm.arch");
  }
  if (bits == 0) {
    bits = (int)r_config_get_i(core->config, "asm.bits");
  }

  if (!arch || !*arch) {
    arch = "x86";
  }

  if (r_str_startswith(arch, "arm") || r_str_startswith(arch, "aarch")) {
    if (bits == 64 || r_str_eq(arch, "aarch64") || r_str_eq(arch, "arm64")) {
      return &conv_arm64;
    }
    return &conv_arm32;
  }

  if (r_str_eq(arch, "x86") || r_str_eq(arch, "i386")) {
    if (bits == 32) {
      return &conv_x86_32;
    }
    return &conv_x86_64;
  }

  // Fallback by probing registers in the active register profile only if unknown
  if (core->anal && core->anal->reg) {
    if (r_reg_get(core->anal->reg, "x8", -1) != NULL) {
      return &conv_arm64;
    }
    if (r_reg_get(core->anal->reg, "r7", -1) != NULL && r_reg_get(core->anal->reg, "x0", -1) == NULL) {
      return &conv_arm32;
    }
    if (r_reg_get(core->anal->reg, "rax", -1) != NULL) {
      return &conv_x86_64;
    }
    if (r_reg_get(core->anal->reg, "eax", -1) != NULL) {
      return &conv_x86_32;
    }
  }

  return (bits == 32) ? &conv_x86_32 : &conv_x86_64;
}

const char *help_msg_p[] = {
    "psy", "", "Print syscall name, arguments, and decoded flags",
    "psyc", "", "Print and add syscall call and arguments as comment at PC",
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
    free(flags->desc);
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
    free_flags(curr->signals);
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

void argument_detail(RCore *core, const SyscallConvention *conv, argument *arg) {
  if (!core || !core->anal || !core->anal->reg || !arg || !conv) {
    return;
  }
  if (arg->pos >= 1 && arg->pos <= SYSCALL_REG_COUNT) {
    const char *reg_name = conv->arg_regs[arg->pos - 1];
    if (reg_name) {
      RRegItem *item = r_reg_get(core->anal->reg, reg_name, -1);
      if (item) {
        arg->value = r_reg_get_value(core->anal->reg, item);
      }
    }
  }
}

static bool is_syscall_instruction(const RAnalOp *op) {
  if (!op) {
    return false;
  }
  if (!op->mnemonic) {
    return op->type == R_ANAL_OP_TYPE_SWI;
  }

  // x86-64 / modern x86
  if (r_str_startswith(op->mnemonic, "syscall") ||
      r_str_startswith(op->mnemonic, "sysenter")) {
    return true;
  }
  // ARM / AArch64
  if (r_str_startswith(op->mnemonic, "svc") ||
      r_str_startswith(op->mnemonic, "swi")) {
    return true;
  }
  // x86 32-bit Linux syscall (int 0x80)
  if (r_str_startswith(op->mnemonic, "int")) {
    return op->val == 0x80 || strstr(op->mnemonic, "0x80") != NULL ||
           (op->size >= 2 && op->bytes && op->bytes[0] == 0xcd && op->bytes[1] == 0x80);
  }

  return false;
}

/**
 * Read a null-terminated string from target process memory via RCore
 * Returns a newly allocated string (caller must free) or NULL on error
 */
char *read_string_from_target(RCore *core, uint64_t addr, size_t max_len) {
  if (addr == 0 || !core || !core->io) {
    return NULL;
  }

  char *buffer = calloc(1, max_len + 1);
  if (!buffer) {
    return NULL;
  }

  // Use radare2's IO interface to read memory
  bool ok = r_io_read_at(core->io, addr, (uint8_t *)buffer, max_len);

  if (!ok) {
    free(buffer);
    return NULL;
  }

  // Ensure null termination at maximum read boundary
  buffer[max_len] = '\0';

  return buffer;
}

void find_syscall(RCore *core, const SyscallConvention *conv, int callnum,
                  ut64 current_addr, bool add_comment) {
  if (!core || !core->anal || !core->anal->syscall) {
    return;
  }

  RSyscallItem *si = NULL;
  if (callnum >= 0 && callnum < 0xFFFF) {
    si = r_syscall_get(core->anal->syscall, callnum, -1);
  }

  if (!si) {
    r_cons_printf(core->cons, "syscall_%d();\n", callnum);
    if (add_comment) {
      char tmp[64];
      snprintf(tmp, sizeof(tmp), "syscall_%d();", callnum);
      r_meta_set_string(core->anal, R_META_TYPE_COMMENT, current_addr, tmp);
      r_cons_printf(core->cons, "Added comment at 0x%08" PFMT64x "\n", current_addr);
    }
    return;
  }

  RStrBuf *sb = r_strbuf_new("");
  r_strbuf_appendf(sb, "%s( ", si->name);

  RJson *db_json = load_syscall_db();
  iterate_argument_string(core, conv, sb, db_json, si->name, (size_t)si->args, si->sargs);
  if (db_json) {
    r_json_free(db_json);
  }
  r_syscall_item_free(si);

  char *call_str = r_strbuf_drain(sb);
  if (call_str) {
    r_cons_printf(core->cons, "%s\n", call_str);
    if (add_comment) {
      r_meta_set_string(core->anal, R_META_TYPE_COMMENT, current_addr, call_str);
      r_cons_printf(core->cons, "Added comment at 0x%08" PFMT64x "\n", current_addr);
    }
    free(call_str);
  }
}

bool is_syscall(RCorePluginSession *cps, bool add_comment) {
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
    if (!is_syscall_instruction(&op)) {
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

  const SyscallConvention *conv = get_syscall_convention(core);
  if (!conv || !conv->syscall_reg) {
    r_cons_printf(core->cons, "Error: Unknown architecture calling convention\n");
    r_anal_op_fini(&op);
    r_cons_flush(core->cons);
    return false;
  }

  RRegItem *item = r_reg_get(core->anal->reg, conv->syscall_reg, -1);
  if (!item && conv->alt_syscall_reg) {
    item = r_reg_get(core->anal->reg, conv->alt_syscall_reg, -1);
  }

  if (item) {
    ut64 syscall_number = r_reg_get_value(core->anal->reg, item);
    find_syscall(core, conv, (int)syscall_number, current_addr, add_comment);
  } else {
    r_cons_printf(core->cons,
                  "Could not find syscall register '%s' for arch '%s'\n",
                  conv->syscall_reg, conv->name);
  }

  r_anal_op_fini(&op);
  r_cons_flush(core->cons);
  return true;
}

bool read_sys_call(RCorePluginSession *cps, const char *input) {
  if (!cps || !cps->core) {
    return false;
  }
  r_core_autocomplete_add(cps->core->autocomplete, "ps psy psyc",
                          R_CORE_AUTOCMPLT_DFLT, true);
  RCore *core = cps->core;
  if (r_str_eq(input, "psy")) {
    return is_syscall(cps, false);
  } else if (r_str_eq(input, "psyc")) {
    return is_syscall(cps, true);
  } else if (r_str_eq(input, "ps?") || r_str_eq(input, "psy?") || r_str_eq(input, "psyc?")) {
    r_core_cmd_help(core, help_msg_p);
    return true;
  }
  return false;
}

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
