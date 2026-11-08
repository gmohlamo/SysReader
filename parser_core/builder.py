"""
SyscallDatabaseBuilder module for SysReader.
Orchestrates header scanning, macro evaluation, routing, and schema assembly.
"""

import os
import json
from .config import DEFAULT_HEADERS, MACRO_BLACKLIST, PREFERRED_NAMES
from .routing import PREFIX_ROUTING
from .schemas import get_base_syscall_schemas, FALLBACK_STRUCTS
from .evaluator import (
    scan_all_headers,
    scan_structs,
    evaluate_macros,
    filter_flags,
)


class SyscallDatabaseBuilder:
    def __init__(self, extra_headers=None):
        self.header_paths = list(DEFAULT_HEADERS)
        if extra_headers:
            for eh in extra_headers:
                if eh not in self.header_paths:
                    self.header_paths.append(eh)

        self.macro_blacklist = set(MACRO_BLACKLIST)
        self.preferred_names = dict(PREFERRED_NAMES)
        self.prefix_routing = dict(PREFIX_ROUTING)

        self.raw_macros = {}
        self.constants = {}
        self.structs = {}

    def _extract_all_target_prefixes(self):
        """Extracts all configured macro prefixes across all syscalls and struct fields."""
        target_prefixes = set()
        for sc in self.prefix_routing.values():
            for item in sc.values():
                if isinstance(item, list):
                    target_prefixes.update(item)
                elif isinstance(item, dict):
                    for sub in item.values():
                        if isinstance(sub, list):
                            target_prefixes.update(sub)
        return target_prefixes

    def build_database(self):
        """Builds the complete syscall database structure."""
        self.raw_macros = scan_all_headers(self.header_paths)
        self.structs = scan_structs(self.header_paths)

        target_prefixes = self._extract_all_target_prefixes()
        self.constants = evaluate_macros(
            self.raw_macros,
            blacklist=self.macro_blacklist,
            target_prefixes=target_prefixes,
        )

        database = get_base_syscall_schemas()

        # 1. Process standard argument flags and signals
        for sc_name, sc_data in database.items():
            if sc_name in self.prefix_routing and "arguments" in sc_data:
                for arg_name, routing_spec in self.prefix_routing[sc_name].items():
                    if arg_name == "struct_fields":
                        continue
                    for arg_idx, arg_meta in sc_data["arguments"].items():
                        if arg_meta["name"] == arg_name:
                            if isinstance(routing_spec, list):
                                matched = {}
                                for k, v in self.constants.items():
                                    if any(k == p or k.startswith(p) for p in routing_spec):
                                        matched[k] = v
                                clean_matched = filter_flags(
                                    matched,
                                    target_arg_name=arg_meta["name"],
                                    blacklist=self.macro_blacklist,
                                    preferred_names=self.preferred_names,
                                )
                                if clean_matched:
                                    arg_meta["flags"] = clean_matched
                            elif isinstance(routing_spec, dict):
                                if "flags" in routing_spec:
                                    prefixes = routing_spec["flags"]
                                    matched = {}
                                    for k, v in self.constants.items():
                                        if any(k == p or k.startswith(p) for p in prefixes):
                                            matched[k] = v
                                    clean_matched = filter_flags(
                                        matched,
                                        target_arg_name=arg_meta["name"],
                                        blacklist=self.macro_blacklist,
                                        preferred_names=self.preferred_names,
                                    )
                                    if clean_matched:
                                        arg_meta["flags"] = clean_matched
                                if "signals" in routing_spec:
                                    prefixes = routing_spec["signals"]
                                    matched = {}
                                    for k, v in self.constants.items():
                                        if any(k == p or k.startswith(p) for p in prefixes):
                                            matched[k] = v
                                    clean_matched = filter_flags(
                                        matched,
                                        target_arg_name=arg_meta["name"],
                                        blacklist=self.macro_blacklist,
                                        preferred_names=self.preferred_names,
                                    )
                                    if clean_matched:
                                        arg_meta["signals"] = clean_matched

        # 2. Process nested struct fields (e.g., clone3 -> clone_args, openat2 -> open_how)
        for sc_name, sc_data in database.items():
            if sc_name in self.prefix_routing and "struct_fields" in self.prefix_routing[sc_name]:
                routing_fields = self.prefix_routing[sc_name]["struct_fields"]
                for arg_idx, arg_meta in sc_data["arguments"].items():
                    if arg_meta.get("is_struct"):
                        s_name = arg_meta["struct_name"]
                        struct_fields_dict = {}

                        # Fallback definitions if kernel headers omit struct body in user space
                        discovered_fields = self.structs.get(s_name) or FALLBACK_STRUCTS.get(s_name)

                        if discovered_fields:
                            for idx, field in enumerate(discovered_fields):
                                field_entry = {
                                    "name": field["name"],
                                    "type": field["type"],
                                    "field_index": idx,
                                }
                                if field["name"] in routing_fields:
                                    f_spec = routing_fields[field["name"]]
                                    if isinstance(f_spec, list):
                                        matched = {}
                                        for k, v in self.constants.items():
                                            if any(k == p or k.startswith(p) for p in f_spec):
                                                matched[k] = v
                                        clean_matched = filter_flags(
                                            matched,
                                            target_arg_name=field["name"],
                                            blacklist=self.macro_blacklist,
                                            preferred_names=self.preferred_names,
                                        )
                                        if clean_matched:
                                            field_entry["flags"] = clean_matched
                                    elif isinstance(f_spec, dict):
                                        if "flags" in f_spec:
                                            matched = {}
                                            for k, v in self.constants.items():
                                                if any(k == p or k.startswith(p) for p in f_spec["flags"]):
                                                    matched[k] = v
                                            clean_matched = filter_flags(
                                                matched,
                                                target_arg_name=field["name"],
                                                blacklist=self.macro_blacklist,
                                                preferred_names=self.preferred_names,
                                            )
                                            if clean_matched:
                                                field_entry["flags"] = clean_matched
                                        if "signals" in f_spec:
                                            matched = {}
                                            for k, v in self.constants.items():
                                                if any(k == p or k.startswith(p) for p in f_spec["signals"]):
                                                    matched[k] = v
                                            clean_matched = filter_flags(
                                                matched,
                                                target_arg_name=field["name"],
                                                blacklist=self.macro_blacklist,
                                                preferred_names=self.preferred_names,
                                            )
                                            if clean_matched:
                                                field_entry["signals"] = clean_matched

                                struct_fields_dict[str(idx)] = field_entry

                            arg_meta["struct_fields"] = struct_fields_dict

        return database

    def save_to_json(self, output_path="data/syscalls.json"):
        """Generates and writes the database to the specified JSON file."""
        db = self.build_database()
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=4)
        print(f"[+] Successfully generated robust syscall database at {output_path} with {len(db)} syscall mappings!")
        return db
