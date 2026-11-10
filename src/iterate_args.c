#include "../include/readsys.h"
#include <ctype.h>

void iterate_argument_string(RCore *core, const SyscallConvention *conv,
                             RStrBuf *sb, const RJson *db_json,
                             const char *name, size_t arg_count,
                             char *arg_str) {
  if (!core || !sb) {
    return;
  }

  // Create arguments list
  args *arg_head = calloc(1, sizeof(args));
  if (!arg_head) {
    return;
  }

  // Check if we have argument count from DB
  const RJson *sc_node = db_json ? r_json_get(db_json, name) : NULL;
  size_t effective_count = arg_count;
  if (sc_node) {
    const RJson *sc_args_count = r_json_get(sc_node, "args");
    if (sc_args_count && sc_args_count->type == R_JSON_INTEGER && sc_args_count->num.u_value > 0) {
      effective_count = (size_t)sc_args_count->num.u_value;
    }
  }

  // Parse formatting tokens from arg_str if available
  char *format = NULL;
  char *args_itr = arg_str ? strdup(arg_str) : NULL;
  if (args_itr) {
    char *token = strtok(args_itr, " ");
    if (token) {
      format = strdup(token);
    }
  }

  size_t format_len = format ? strlen(format) : 0;
  arg_head->length = effective_count > 0 ? effective_count : arg_count;
  argument *tail = NULL;

  for (size_t itr = 0; itr < arg_head->length; itr++) {
    char *token = args_itr ? strtok(NULL, " ") : NULL;

    argument *argument_node = calloc(1, sizeof(argument));
    if (!argument_node) {
      break;
    }

    if (token) {
      argument_node->name = remove_newline(token);
    } else {
      char tmp_name[32];
      snprintf(tmp_name, sizeof(tmp_name), "arg%zu", itr);
      argument_node->name = strdup(tmp_name);
    }

    argument_node->type = (itr < format_len) ? format[itr] : 'x';
    argument_node->pos = (unsigned int)(itr + 1);

    if (!arg_head->args) {
      arg_head->args = argument_node;
    } else {
      tail->next = argument_node;
    }
    tail = argument_node;
  }

  free(args_itr);
  free(format);

  argument *list_itr = arg_head->args;
  while (list_itr) {
    argument_detail(core, conv, list_itr);

    int param_idx = (int)(list_itr->pos - 1);
    const char *db_name = get_arg_name_from_db(db_json, name, param_idx);
    if (db_name && (strncmp(list_itr->name, "arg", 3) == 0 || strlen(list_itr->name) == 0)) {
      free(list_itr->name);
      list_itr->name = strdup(db_name);
    }

    r_strbuf_appendf(sb, "%s = ", list_itr->name ? list_itr->name : "unknown");

    list_itr->flags = get_flags_for_arg(db_json, name, param_idx);
    list_itr->signals = get_signals_for_arg(db_json, name, param_idx);

    const char *db_type = get_arg_type_from_db(db_json, name, param_idx);
    bool is_string = (list_itr->type == 'z') ||
                     (db_type && strstr(db_type, "char *") != NULL) ||
                     (list_itr->name && (strstr(list_itr->name, "path") != NULL ||
                                         strstr(list_itr->name, "filename") != NULL ||
                                         strstr(list_itr->name, "name") != NULL));

    if (list_itr->flags != NULL || list_itr->signals != NULL) {
      print_flag_details(sb, list_itr->value, list_itr->flags, list_itr->signals);
    } else if (is_string && list_itr->value != 0) {
      char *str = read_string_from_target(core, list_itr->value, MAX_STRING_PREVIEW);
      if (str) {
        r_strbuf_append(sb, "\"");
        for (size_t i = 0; str[i] != '\0' && i < MAX_STRING_PREVIEW; i++) {
          if (isprint((unsigned char)str[i]) && str[i] != '"') {
            r_strbuf_appendf(sb, "%c", str[i]);
          } else {
            r_strbuf_appendf(sb, "\\x%02x", (unsigned char)str[i]);
          }
        }
        r_strbuf_appendf(sb, "\" @ 0x%" PRIx64, list_itr->value);
        free(str);
      } else {
        r_strbuf_appendf(sb, "0x%" PRIx64, list_itr->value);
      }
    } else {
      switch (list_itr->type) {
      case 'x':
      case 'i':
        r_strbuf_appendf(sb, "0x%" PRIx64, list_itr->value);
        break;
      case 'p':
        r_strbuf_appendf(sb, "*0x%" PRIx64, list_itr->value);
        break;
      case 's':
        r_strbuf_appendf(sb, "%" PRIu64, list_itr->value);
        break;
      default:
        r_strbuf_appendf(sb, "0x%" PRIx64, list_itr->value);
        break;
      }
    }

    list_itr = list_itr->next;
    if (list_itr != NULL) {
      r_strbuf_append(sb, ", ");
    }
  }
  r_strbuf_append(sb, ");");

  free_args(arg_head);
}
