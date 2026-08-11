/* radare - Copyright 2025 - yourname */

#include <ctype.h>
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
static const char *syscall_regs[] = {
    "rdi", // arg 1
    "rsi", // arg 2
    "rdx", // arg 3
    "r10", // arg 4 (note: r10 for syscalls, NOT rcx)
    "r8",  // arg 5
    "r9"   // arg 6
};

#define SYSCALL_REG_COUNT 6

static const char *help_msg_p[] = {
    "psy", "",
    "If rip is on a systemcall, add function call and arguments as comment",
    NULL};

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

static char *remove_newline(const char *str) {
  if (!str) {
    return NULL;
  }
  char *newline = strchr(str, '\n');
  if (newline) {
    return r_str_ndup(str, newline - str);
  }
  return strdup(str);
}

static void free_flags(flag_entry *flags) {
  while (flags) {
    flag_entry *next = flags->next;
    free(flags->name);
    free(flags);
    flags = next;
  }
}

static void free_args(args *arg_head) {
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

static RJson *load_syscall_db(void) {
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

static flag_entry *get_flags_for_arg(const RJson *root,
                                     const char *syscall_name,
                                     int param_index) {
  if (!root || !syscall_name) {
    return NULL;
  }

  const RJson *sc_node = r_json_get(root, syscall_name);
  if (!sc_node) {
    return NULL;
  }

  const RJson *args_node = r_json_get(sc_node, "arguments");
  if (!args_node) {
    return NULL;
  }

  char param_idx_str[16];
  snprintf(param_idx_str, sizeof(param_idx_str), "%d", param_index);

  const RJson *arg_node = r_json_get(args_node, param_idx_str);
  if (!arg_node) {
    return NULL;
  }

  const RJson *flags_node = r_json_get(arg_node, "flags");
  if (!flags_node || flags_node->type != R_JSON_OBJECT) {
    return NULL;
  }

  flag_entry *head_flag = NULL;
  const RJson *item;
  for (item = flags_node->children.first; item; item = item->next) {
    if (!item->key) {
      continue;
    }
    flag_entry *new_flag = malloc(sizeof(flag_entry));
    if (!new_flag) {
      break;
    }
    new_flag->name = strdup(item->key);
    new_flag->value = (uint64_t)item->num.u_value;
    new_flag->next = head_flag;
    head_flag = new_flag;
  }

  return head_flag;
}

void print_flag_details(RCore *core, uint64_t value, flag_entry *flags) {
  if (!flags) {
    r_cons_printf(core->cons, "0x%" PRIx64, value);
    return;
  }

  r_cons_printf(core->cons, "0x%" PRIx64 " (", value);
  int first = 1;

  // Handle exact 0 matches (e.g., PROT_NONE = 0, O_RDONLY = 0)
  if (value == 0) {
    flag_entry *curr = flags;
    while (curr != NULL) {
      if (curr->value == 0) {
        r_cons_printf(core->cons, "%s", curr->name);
        first = 0;
        break;
      }
      curr = curr->next;
    }
  }

  // Evaluate bitwise and exclusive flags
  flag_entry *curr = flags;
  while (curr != NULL) {
    if (curr->value != 0) {
      // Check if the flag bit(s) are set
      if ((value & curr->value) == curr->value) {
        if (!first) {
          r_cons_printf(core->cons, " | ");
        }
        r_cons_printf(core->cons, "%s", curr->name);
        first = 0;
      }
    }
    curr = curr->next;
  }

  if (first && value != 0) {
    r_cons_printf(core->cons, "UNKNOWN");
  }
  r_cons_printf(core->cons, ")");
}

static void argument_detail(RCore *core, argument *arg) {
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
static char *read_string_from_target(RCore *core, uint64_t addr,
                                     size_t max_len) {
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

void iterate_argument_string(RCore *core, const RJson *db_json,
                             const char *name, size_t arg_count,
                             char *arg_str) {
  if (!core || !arg_str) {
    return;
  }
  char *args_itr = strdup(arg_str);
  if (!args_itr) {
    return;
  }

  char *token = strtok(args_itr, " ");
  if (!token) {
    free(args_itr);
    return;
  }
  char *format = strdup(token);
  if (!format) {
    free(args_itr);
    return;
  }

  size_t format_len = strlen(format);
  size_t itr = 0;
  args *arg_head = calloc(1, sizeof(args));
  if (!arg_head) {
    free(args_itr);
    free(format);
    return;
  }

  arg_head->length = arg_count;
  argument *tail = NULL;

  while (itr < arg_head->length) {
    token = strtok(NULL, " ");
    if (!token) {
      break;
    }

    argument *argument_node = calloc(1, sizeof(argument));
    if (!argument_node) {
      break;
    }

    argument_node->name = remove_newline(token);
    argument_node->type = (itr < format_len) ? format[itr] : 'x';
    argument_node->pos = (unsigned int)(itr + 1);

    if (!arg_head->args) {
      arg_head->args = argument_node;
    } else {
      tail->next = argument_node;
    }
    tail = argument_node;
    itr++;
  }

  argument *list_itr = arg_head->args;
  while (list_itr) {
    argument_detail(core, list_itr);
    /*r_cons_printf(
        core->cons, "{type: %c, Pos: %d, Name: %s} = Value: ", list_itr->type,
        list_itr->pos - 1, list_itr->name ? list_itr->name : "unknown");*/
    r_cons_printf(core->cons,
                  "%s = ", list_itr->name ? list_itr->name : "unknown");

    list_itr->flags = get_flags_for_arg(db_json, name, list_itr->pos - 1);

    switch (list_itr->type) {
    case 'x':
    case 'i':
      if (list_itr->flags != NULL) {
        print_flag_details(core, list_itr->value, list_itr->flags);
      } else {
        if (list_itr->type == 'x') {
          r_cons_printf(core->cons, "0x%" PRIx64, list_itr->value);
        } else {
          r_cons_printf(core->cons, "%" PRId64, (int64_t)list_itr->value);
        }
      }
      break;
    case 'p':
      r_cons_printf(core->cons, "*0x%" PRIx64, list_itr->value);
      break;
    case 'z': {
      char *str =
          read_string_from_target(core, list_itr->value, MAX_STRING_PREVIEW);
      if (str) {
        r_cons_printf(core->cons, "\"");
        for (size_t i = 0; str[i] != '\0' && i < MAX_STRING_PREVIEW; i++) {
          if (isprint((unsigned char)str[i]) && str[i] != '"') {
            r_cons_printf(core->cons, "%c", str[i]);
          } else {
            r_cons_printf(core->cons, "\\x%02x", (unsigned char)str[i]);
          }
        }
        r_cons_printf(core->cons, "...\" @ 0x%" PRIx64, list_itr->value);
        free(str);
      } else {
        r_cons_printf(core->cons, "(error reading string) @ 0x%" PRIx64,
                      list_itr->value);
      }
    } break;
    case 's':
      r_cons_printf(core->cons, "%" PRIu64, list_itr->value);
      break;
    default:
      r_cons_printf(core->cons, "0x%" PRIx64, list_itr->value);
      break;
    }

    // r_cons_printf(core->cons, "\n");
    list_itr = list_itr->next;
    if (list_itr != NULL)
      r_cons_printf(core->cons, ", ");
  }
  r_cons_printf(core->cons, ");\n");

  free(args_itr);
  free(format);
  free_args(arg_head);
}

void break_argument_string(RCore *core, const RJson *db_json, const char *name,
                           const char *arg_str) {
  if (!arg_str) {
    return;
  }
  char *arg_cpy = strdup(arg_str);
  if (!arg_cpy) {
    return;
  }

  // split by comma
  char *token = strtok(arg_cpy, ","); // interrupt vector e.g. 0x80
  if (!token) {
    free(arg_cpy);
    return;
  }

  token = strtok(NULL, ","); // syscall num
  if (!token) {
    free(arg_cpy);
    return;
  }

  token = strtok(NULL, ","); // arg count
  if (!token) {
    free(arg_cpy);
    return;
  }
  long count = atol(token);

  token = strtok(NULL, ","); // argument format and names string
  if (token) {
    iterate_argument_string(core, db_json, name, (size_t)count, token);
  }

  free(arg_cpy);
}

void find_syscall(RCore *core, RRegItem *reg_item) {
  if (!core || !reg_item) {
    return;
  }
  int callnum = (int)r_reg_get_value(core->anal->reg, reg_item);
  // r_cons_printf(core->cons, "Symbol num in find function: %d\n", callnum);

  const char *name_raw = r_core_cmd_strf(core, "asl %d", callnum);
  if (!name_raw) {
    return;
  }
  char *dup_name = remove_newline(name_raw);
  free((void *)name_raw);

  if (!dup_name || !*dup_name) {
    free(dup_name);
    return;
  }

  const char *arguments_raw = r_core_cmd_strf(core, "ask %s", dup_name);
  r_cons_printf(core->cons, "%s( ", dup_name);

  if (arguments_raw) {
    RJson *db_json = load_syscall_db();
    break_argument_string(core, db_json, dup_name, arguments_raw);
    if (db_json) {
      r_json_free(db_json);
    }
    free((void *)arguments_raw);
  }

  free(dup_name);
}

static bool addSymbolComments(RCorePluginSession *cps, const char *input) {
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
  ut8 buf[32];
  ut64 current_addr = core->addr;

  r_io_read_at(core->io, current_addr, buf, sizeof(buf));

  int ret = r_anal_op(core->anal, &op, current_addr, buf, sizeof(buf),
                      R_ARCH_OP_MASK_DISASM);

  if (ret > 0) {
    if (r_str_eq(op.mnemonic, "syscall") || r_str_eq(op.mnemonic, "int 0x80") ||
        r_str_eq(op.mnemonic, "sysenter")) {
      // r_cons_printf(core->cons, "Looks like we landed on a system call\n");
      // r_cons_printf(core->cons, "Address: %08" PFMT64x "\n", current_addr);
      // r_cons_printf(core->cons, "Mnemonic: %s\n", op.mnemonic);
      // r_cons_printf(core->cons, "Size: %d bytes\n", op.size);
    } else {
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

  RRegItem *rax_item = r_reg_get(core->anal->reg, "rax", R_REG_TYPE_GPR);
  if (rax_item) {
    // r_cons_printf(core->cons, "Register Name: %s\n", rax_item->name);
    /*r_cons_printf(core->cons, "Register Value: %" PRIu64 "\n",
                  r_reg_get_value(core->anal->reg, rax_item));*/
    // r_cons_printf(core->cons, "Register Size: 0x%08x\n", rax_item->size);
    // r_cons_printf(core->cons, "Register Offset: 0x%08x\n", rax_item->offset);
    find_syscall(core, rax_item);
  } else {
    r_cons_printf(core->cons, "Could not find rax register\n");
  }

  r_anal_op_fini(&op);
  r_cons_flush(core->cons);
  return true;
}

static bool read_sys_call(RCorePluginSession *cps, const char *input) {
  if (!cps || !cps->core) {
    return false;
  }
  r_core_autocomplete_add(cps->core->autocomplete, "ps psy",
                          R_CORE_AUTOCMPLT_DFLT, true);
  RCore *core = cps->core;
  if (r_str_eq(input, "psy")) {
    return addSymbolComments(cps, input);
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
RCorePlugin r_core_plugin_print_syscall = {
    .meta =
        {
            .name = "psy",
            .desc = "Reads symbols at runtime to give you syscall names and "
                    "arguments",
            .author = "Fredd0Bangz",
            .license = "MIT",
        },
    .call = read_sys_call,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {.type = R_LIB_TYPE_CORE,
                                  .data = &r_core_plugin_print_syscall,
                                  .version = R2_VERSION,
                                  .abiversion = R2_ABIVERSION};
#endif
