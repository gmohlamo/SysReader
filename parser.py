#!/usr/bin/env python3
import os
import re
import json

class SyscallDatabaseBuilder:
    def __init__(self):
        self.constants = {}
        self.structs = {}
        # Define header files to scan dynamically from the host system
        self.header_paths = [
            "/usr/include/linux/mman.h",
            "/usr/include/asm-generic/mman.h",
            "/usr/include/asm-generic/mman-common.h",
            "/usr/include/x86_64-linux-gnu/bits/mman-linux.h",
            "/usr/include/x86_64-linux-gnu/bits/mman-map-flags-generic.h",
            "/usr/include/linux/sched.h",
            "/usr/include/linux/fcntl.h",
            "/usr/include/fcntl.h",
            "/usr/include/x86_64-linux-gnu/asm/fcntl.h",
            "/usr/include/x86_64-linux-gnu/bits/fcntl-linux.h",
            "/usr/include/asm-generic/fcntl.h",
            "/usr/include/asm-generic/unistd.h",
            "/usr/include/linux/unistd.h",
            "/usr/include/tcl8.6/tcl-private/compat/unistd.h",
            "/usr/include/tcl8.6/tk-private/compat/unistd.h",
            "/usr/include/unistd.h",
            "/usr/include/x86_64-linux-gnu/asm/unistd.h",
            "/usr/include/x86_64-linux-gnu/bits/unistd.h",
            "/usr/include/x86_64-linux-gnu/sys/unistd.h",
            "/usr/include/x86_64-linux-gnu/asm/signal.h"
        ]
        
        # Mapping rules: Which macro prefixes belong to which syscall and argument name
        self.prefix_routing = {
            "open": {
                "flags": ["O_"],
                "mode": ["S_I"],
            },
            "mmap": {
                "prot": ["PROT_"],
                "flags": ["MAP_"]
            },
            "mremap": {
                "flags": ["MREMAP_"]
            },
            "msync": {
                "flags": ["MS_"]
            },
            "clone": {
                "flags": ["CLONE_", "SIG"]
            },
            "clone3": {
                # Maps directly to the struct field inside clone_args
                "struct_fields": {
                    "flags": ["CLONE_", "SIG"]
                }
            },
            "open": {
                "flags": ["O_"],
                "mode": ["S_IR", "S_IW", "S_IX", "S_IRWX"]
            },
            "openat": {
                "flags": ["O_"],
                "mode": ["S_IR", "S_IW", "S_IX", "S_IRWX"]
            },
            "execveat": {
                "flags": ["AT_"]
            },
            "mlock2": {
                "flags": ["MCL_"]
            },
        }

    def parse_c_int(self, val_str):
        """Robustly parses C-style integer values (decimal, hex, and octal)."""
        val_str = val_str.strip()
        if val_str.startswith("0x") or val_str.startswith("0X"):
            return int(val_str, 16)
        elif val_str.startswith("0b") or val_str.startswith("0B"):
            return int(val_str, 2)
        elif val_str.startswith("0o") or val_str.startswith("0O"):
            return int(val_str, 8)
        # Handle C-style octal notation (e.g., 0100, 0200)
        elif val_str.startswith("0") and len(val_str) > 1 and all(c in '01234567' for c in val_str):
            return int(val_str, 8)
        else:
            return int(val_str, 10)

    def scan_headers(self):
        """Scans local system headers for #define macros and evaluates their values."""
        macro_pattern = re.compile(r'^\s*#\s*define\s+([A-Z0-9_]+)\s+([0-9xX]+|\b[A-Z0-9_]+\b)', re.MULTILINE)
        # Regex to match C struct blocks, e.g., struct clone_args { ... };
        struct_pattern = re.compile(r'struct\s+([a-zA-Z0-9_]+)\s*\{([^}]+)\};', re.DOTALL)
        
        for path in self.header_paths:
            if not os.path.exists(path):
                print(f"[-] Skipping missing header: {path}")
                continue
            
            print(f"[*] Parsing headers from: {path}")
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # 1. Parse macros
                for match in macro_pattern.finditer(content):
                    name, val_str = match.groups()
                    try:
                        self.constants[name] = self.parse_c_int(val_str)
                    except ValueError:
                        if val_str in self.constants:
                            self.constants[name] = self.constants[val_str]

                # 2. Parse structs
                for match in struct_pattern.finditer(content):
                    s_name, s_body = match.groups()
                    fields = []
                    # Match individual lines inside the struct body: type name;
                    field_pattern = re.compile(r'^\s*([a-zA-Z0-9_*]+(?:\s+[a-zA-Z0-9_*]+)*)\s+([a-zA-Z0-9_]+)\s*(?:\[\s*\d*\s*\])?\s*;', re.MULTILINE)
                    
                    for f_match in field_pattern.finditer(s_body):
                        f_type, f_name = f_match.groups()
                        fields.append({"name": f_name, "type": f_type.strip()})
                    
                    if fields:
                        self.structs[s_name] = fields

    def build_database(self):
        # Builds syscall database
        self.scan_headers()

        # Skeleton of target system calls with basic structural positions
        database = {
            "open": {
                "args": 3,
                "arguments": {
                    "0": {"name": "filename", "type": "const char *", "param_index": 0},
                    "1": {"name": "flags", "type": "int", "param_index": 1},
                    "2": {"name": "mode", "type": "umode_t", "param_index": 2},
                }
            },
            "mmap": {
                "args": 6,
                "arguments": {
                    "2": {"name": "prot", "type": "int", "param_index": 2},
                    "3": {"name": "flags", "type": "int", "param_index": 3}
                }
            },
            "mremap": {
                "args": 5,
                "arguments": {
                    "3": {"name": "flags", "type": "int", "param_index": 3}
                }
            },
            "msync": {
                "args": 3,
                "arguments": {
                    "2": {"name": "flags", "type": "int", "param_index": 2}
                }
            },
            "clone": {
                "args": 5,
                "arguments": {
                    "0": {"name": "flags", "type": "unsigned long", "param_index": 0}
                }
            },
            "clone3": {
                "args": 2,
                "arguments": {
                    "0": {
                        "name": "uargs",
                        "type": "struct clone_args *",
                        "param_index": 0,
                        "is_struct": True,
                        "struct_name": "clone_args"
                    },
                    "1": {"name": "size", "type": "size_t", "param_index": 1}
                }
            },
            "openat": {
                "args": 4,
                "arguments": {
                    "0": {"name": "dirfd", "type": "int", "param_index": 0},
                    "1": {"name": "pathname", "type": "const char *", "param_index": 1},
                    "2": {"name": "flags", "type": "int", "param_index": 2},
                    "3": {"name": "mode", "type": "mode_t", "param_index": 3}
                }
            },
            "open": {
                "args": 3,
                "arguments": {
                    "1": {"name": "flags", "type": "int", "param_index": 1},
                    "2": {"name": "mode", "type": "mode_t", "param_index": 2}
                }
            },
            "execveat": {
                "args": 5,
                "arguments": {
                    "0": {"name": "dfd", "type": "int", "param_index": 0},
                    "1": {"name": "filename", "type": "const char *", "param_index": 1},
                    "2": {"name": "argv", "type": "const char *const *", "param_index": 2},
                    "3": {"name": "envp", "type": "const char *const *", "param_index": 3},
                    "4": {"name": "flags", "type": "int", "param_index": 4},
                }
            },
            "mlock2": {
                "args": 3,
                "arguments": {
                    "0": {"name": "start", "type": "unsigned long", "param_index": 0},
                    "1": {"name": "len", "type": "size_t", "param_index": 1},
                    "2": {"name": "flags", "type": "int", "param_index": 2},
                }
            },
        }

        # Process standard argument flags
        for sc_name, sc_data in database.items():
            if sc_name in self.prefix_routing and "arguments" in sc_data:
                for arg_name, prefixes in self.prefix_routing[sc_name].items():
                    for arg_idx, arg_meta in sc_data["arguments"].items():
                        if arg_meta["name"] == arg_name:
                            matched_flags = {k: v for k, v in self.constants.items() if any(k.startswith(p) for p in prefixes)}
                            if matched_flags:
                                arg_meta["flags"] = matched_flags

        # Process nested struct fields for advanced syscalls like clone3
        for sc_name, sc_data in database.items():
            if sc_name in self.prefix_routing and "struct_fields" in self.prefix_routing[sc_name]:
                for arg_idx, arg_meta in sc_data["arguments"].items():
                    if arg_meta.get("is_struct") and arg_meta["struct_name"] in self.structs:
                        s_name = arg_meta["struct_name"]
                        struct_fields_dict = {}
                        
                        # Populate fields extracted from kernel headers
                        for idx, field in enumerate(self.structs[s_name]):
                            field_entry = {
                                "name": field["name"],
                                "type": field["type"],
                                "field_index": idx
                            }
                            
                            # Inject flags if this specific field matches routing rules (e.g., 'flags' field)
                            if field["name"] in self.prefix_routing[sc_name]["struct_fields"]:
                                prefixes = self.prefix_routing[sc_name]["struct_fields"][field["name"]]
                                matched_flags = {k: v for k, v in self.constants.items() if any(k.startswith(p) for p in prefixes)}
                                if matched_flags:
                                    field_entry["flags"] = matched_flags
                            
                            struct_fields_dict[str(idx)] = field_entry
                        
                        arg_meta["struct_fields"] = struct_fields_dict

        return database

    def save_to_json(self, output_path="data/syscalls.json"):
        db = self.build_database()
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(db, f, indent=4)
        print(f"[+] Successfully generated robust database at {output_path} with {len(db)} core syscall mappings!")

if __name__ == "__main__":
    builder = SyscallDatabaseBuilder()
    builder.save_to_json()
