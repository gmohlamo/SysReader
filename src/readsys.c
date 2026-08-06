/* radare - Copyright 2025 - yourname */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#define R_LOG_ORIGIN "core.readsys"

#include <r_core.h>
#include <r_syscall.h>
#include <r_util.h>

#define MAX_STRING_PREVIEW 32

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

#define SYSCALL_REG_COUNT 6

static const char *help_msg_p[] = {
    "psy", "",
    "If rip is on a systemcall, add function call and arguments as comment",
    NULL};

// bit of a bold idea, but essentially
// for example: "ask mmap" returns:
//  0x80,9,6,xixxii addr len prot flags fd pgoff
//  This means:
//  0x80: Syscall Interrupt Vector
//  9: The syscall number
//  6: The argument count
//  xixxii: Argument types:
//  	- x: Unsigned Long
//  	- i: Integer
//  	- p: pointer (also an unsigned long)
//  	- z: string (also an unsigned long)
//  	- s: size_t (also an...)
//  In this instance:
//  	-x --> addr (RDI)
//  	-i --> len (RSI)
//  	-x --> prot (RDX)
//  	-x --> flags (R10)
//  	-i --> fd (R8)
//  	-i --> pgoff (R9)
typedef struct flag_entry {
  char *name;
  uint64_t value;
  struct flag_entry *next;
} flag_entry;

typedef struct {
  unsigned int pos;
  char type;
  char *name;
  uint64_t value;
  flag_entry *flags; // Pointer to parsed flags for this argument
  void *next;
} argument;

typedef struct {
  size_t length;
  argument *args;
} args;

void print_flag_details(RCore *core, uint64_t value, flag_entry *flags) {
  if (!flags) {
    r_cons_printf(core->cons, "0x%lx", value);
    return;
  }

  r_cons_printf(core->cons, "0x%lx (", value);
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

// since we are directly allocating memory, we should free it up too
char *remove_newline(char *str) {
  char *sub_str = NULL;
  char *newline = strstr(str, "\n");
  sub_str = strndup(str, (unsigned long)newline - (unsigned long)str);
  return sub_str;
}

void argument_detail(RCore *core, argument *arg) {
  // get list of registers
  RList *register_list = r_reg_get_list(core->anal->reg, -1);
  // Iterate!!!!
  RRegItem *reg_item = 0;
  RListIter *iter = 0;
  r_list_foreach(register_list, iter, reg_item) {
    // get argument details
    if (!strncmp(syscall_regs[arg->pos - 1], reg_item->name, 3)) {
      arg->value = r_reg_get_value(core->anal->reg, reg_item);
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
  if (!buffer)
    return NULL;

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

void iterate_argument_string(RCore *core, size_t arg_count, char *arg_str) {
  char *args_itr = strdup(arg_str);
  char *token = strtok(args_itr, " ");
  char *format = strdup(token);
  size_t itr = 0;
  // now we can go down the count of arguments
  args *arg_head = malloc(sizeof(args));
  bzero(arg_head, sizeof(args));
  arg_head->length = arg_count;
  while (itr < arg_head->length) {
    // ideally, I would like to have this be a linked list? cause we have the
    // type and the argument name
    argument *argument_node = malloc(sizeof(argument));
    bzero(argument_node, sizeof(argument));
    token = strtok(NULL, " ");
    argument_node->name = remove_newline(token);
    argument_node->type = format[itr];
    argument_node->pos = itr + 1;
    if (arg_head->args == NULL)
      arg_head->args = argument_node;
    else {
      argument *list_itr = arg_head->args;
      while (list_itr->next != NULL)
        list_itr = list_itr->next;
      list_itr->next = argument_node;
    }
    itr++;
  }
  argument *list_itr = arg_head->args;
  while (list_itr != NULL) {
    // checked the list, seems to be chilled, now we
    // need to actually get these values
    // argument detail
    argument_detail(core, list_itr);
    r_cons_printf(core->cons, "Iterate. Type: %c, Pos: %d, Name: %s, Value: ",
                  list_itr->type, list_itr->pos, list_itr->name);
    switch (list_itr->type) {
    case 'x':
      r_cons_printf(core->cons, "0x%lx", list_itr->value);
      break;
    case 'i':
      r_cons_printf(core->cons, "%ld", list_itr->value);
      break;
    case 'p':
      r_cons_printf(core->cons, "*0x%lx", list_itr->value);
      break;
    case 'z': {
      char *str =
          read_string_from_target(core, list_itr->value, MAX_STRING_PREVIEW);
      if (str) {
        // Escape non-printable characters for display
        r_cons_printf(core->cons, "\"");
        for (size_t i = 0; str[i] != '\0' && i < MAX_STRING_PREVIEW; i++) {
          if (isprint((unsigned char)str[i]) && str[i] != '"') {
            r_cons_printf(core->cons, "%c", str[i]);
          } else {
            r_cons_printf(core->cons, "\\x%02x", (unsigned char)str[i]);
          }
        }
        r_cons_printf(core->cons, "...\" @ 0x%lx\n", list_itr->value);
        free(str);
      } else {
        r_cons_printf(core->cons, "(error reading string) @ 0x%lx\n",
                      list_itr->value);
      }
    } break;
    case 's':
      r_cons_printf(core->cons, "%zu", list_itr->value);
      break;
    }
    list_itr = list_itr->next;
    r_cons_printf(core->cons, "\n");
  }
  // This seems to work, but I think we need to make a linked list
  free(args_itr);
  free(format);
}

void break_argument_string(RCore *core, const char *arg_str) {
  // copy string
  char *arg_cpy = strdup(arg_str);
  // split by comma
  // we can use strtok
  char *token = strtok(arg_cpy, ",");
  // this gets the syscall
  // we can skip it
  token = strtok(NULL, ",");
  // syscall id, we already know it, skip!
  token = strtok(NULL, ",");
  int count = atol(token);
  // this is what we mainly care about, even after fixing things
  token = strtok(NULL, ",");
  // now to iterate through these arguments
  iterate_argument_string(core, (size_t)count, token);
  free(arg_cpy);
}

void find_syscall(RCore *core, RRegItem *reg_item) {
  int callnum = r_reg_get_value(core->anal->reg, reg_item);
  r_cons_printf(core->cons, "Symbol num in find function: %d\n", callnum);
  // need to find out what the syscall is
  // decided to call the list directly, the problem is that Radare2 is
  // inconsistent when it comes to knowing what is going on through its analysis
  // engine
  const char *name = r_core_cmd_strf(core, "asl %d", callnum);
  char *dup_name = remove_newline((char *)name);
  const char *arguments = r_core_cmd_strf(core, "ask %s", dup_name);
  r_cons_printf(core->cons, "Call Name: %s\n", dup_name);
  free(dup_name);
  break_argument_string(core, arguments);
  // for arguments, we should parse the arguments output
  // let's first handle the register arguments
}

static bool addSymbolComments(RCorePluginSession *cps, const char *input) {
  RCore *core = cps->core;
  if (!core || !core->anal || !core->anal->reg) {
    r_cons_printf(core->cons, "Error: Register profile is not initialised.\n");
  }
  r_debug_reg_sync(core->dbg, R_REG_TYPE_GPR, false);
  // we can get information directly through the Radare2 API
  RAnalOp op = {0};
  ut8 buf[32];

  ut64 current_addr = core->addr;

  // Read bytes from the current address (buf len)
  r_io_read_at(core->io, current_addr, buf, sizeof(buf));

  int ret = r_anal_op(core->anal, &op, current_addr, buf, sizeof(buf),
                      R_ARCH_OP_MASK_DISASM);

  if (ret > 0) {
    /*
r_cons_printf(core->cons, "Address: 0x%08" PFMT64x "\n", current_addr);
r_cons_printf(core->cons, "Mnemonic: %s\n", op.mnemonic);
r_cons_printf(core->cons, "Size: %d bytes\n", op.size);
  */
    if (r_str_eq(op.mnemonic, "syscall") || r_str_eq(op.mnemonic, "int 0x80") ||
        r_str_eq(op.mnemonic, "sysenter")) {
      // figure out what system call we are making
      r_cons_printf(core->cons, "Looks like we landed on a system call");
      r_cons_printf(core->cons, "Address: %08" PFMT64x "\n", current_addr);
      r_cons_printf(core->cons, "Mnemonic: %s\n", op.mnemonic);
      r_cons_printf(core->cons, "Size: %d bytes\n", op.size);
    } else {
      r_cons_printf(core->cons, "Place holder for something smarter\n");
      r_cons_flush(core->cons);
      return true;
    }
  } else {
    r_cons_printf(core->cons,
                  "Failed to decode instruction at 0x%08" PFMT64x "\n",
                  current_addr);
  }
  // get list of registers
  RList *register_list = r_reg_get_list(core->anal->reg, -1);
  // Iterate!!!!
  RRegItem *reg_item = 0;
  RListIter *iter = 0;
  r_list_foreach(register_list, iter, reg_item) {
    if (!strncmp("rax", reg_item->name, 3)) {
      r_cons_printf(core->cons, "Register Name: %s" PFMT64x "\n",
                    reg_item->name);
      r_cons_printf(core->cons, "Register Value: %lu\n",
                    r_reg_get_value(core->anal->reg, reg_item));
      r_cons_printf(core->cons, "Register Size: 0x%08" PFMT64x "\n",
                    (unsigned long)(reg_item->size));
      r_cons_printf(core->cons, "Regsigter Offset: 0x%08" PFMT64x "\n",
                    (unsigned long)(reg_item->offset));
      find_syscall(core, reg_item);
    }
  }
  r_anal_op_fini(&op);
  r_cons_flush(core->cons);
  return true;
}

static bool read_sys_call(RCorePluginSession *cps, const char *input) {
  r_core_autocomplete_add(cps->core->autocomplete, "ps psy",
                          R_CORE_AUTOCMPLT_DFLT, true);
  RCore *core = (RCore *)cps->core;
  if (r_str_eq(input, "psy")) {
    return addSymbolComments(cps, input);
  } else if (r_str_eq(input, "ps?")) {
    r_core_cmd_help(core, help_msg_p);
    return false;
  } else if (r_str_eq(input, "psy?")) {
    RCore *core = (RCore *)cps->core;
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
    //.init = init_psy, // optional
    //.fini = hello_fini, // optional
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {.type = R_LIB_TYPE_CORE,
                                  .data = &r_core_plugin_print_syscall,
                                  .version = R2_VERSION,
                                  .abiversion = R2_ABIVERSION};
#endif
