#include "../include/readsys.h"

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
