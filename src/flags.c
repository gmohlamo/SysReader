#include "../include/readsys.h"

flag_entry *get_flags_for_arg(const RJson *root, const char *syscall_name,
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

  const RJson *arg_node = r_json_get(args_node, param_idx_str);
  if (!arg_node) {
    return NULL;
  }

  const RJson *flags_node = r_json_get(arg_node, "flags");
  if (!flags_node || flags_node->type != R_JSON_OBJECT) {
    return NULL;
  }

  // well Batman, this is a major blunder... essentially:
  // signals aren't like flags and need to be treated using a completely
  // seperate flow we need to augment the JSON to account for signals and
  // iterate through them going from highest to lowest value
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
