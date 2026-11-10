#include "../include/readsys.h"

const char *get_flag_description(const char *name) {
  (void)name;
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
