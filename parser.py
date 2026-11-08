#!/usr/bin/env python3
"""
SysReader Syscall & Flag Database Builder CLI
Entrypoint script for parsing host Linux headers and generating data/syscalls.json.
Refactored into modular components under `parser_core/`.
"""

import os
import sys
import argparse
from parser_core import SyscallDatabaseBuilder


def main():
    parser = argparse.ArgumentParser(
        description="Extract syscall argument flags and constants from system headers using GCC preprocessing."
    )
    parser.add_argument(
        "--output", "-o",
        default="data/syscalls.json",
        help="Target output path for the JSON database (default: data/syscalls.json)"
    )
    parser.add_argument(
        "--extra-headers", "-e",
        nargs="+",
        help="Optional additional C headers to preprocess and scan"
    )
    parser.add_argument(
        "--test-only",
        action="store_true",
        help="Builds database in memory and verifies extraction without writing to disk"
    )

    args = parser.parse_args()

    builder = SyscallDatabaseBuilder(extra_headers=args.extra_headers)

    if args.test_only:
        db = builder.build_database()
        total_flags = sum(
            len(arg.get("flags", {})) + len(arg.get("signals", {}))
            for sc in db.values()
            for arg in sc.get("arguments", {}).values()
        )
        print(f"[+] Test completed successfully: {len(db)} syscalls, {total_flags} total flags/signals parsed.")
    else:
        builder.save_to_json(args.output)


if __name__ == "__main__":
    main()
