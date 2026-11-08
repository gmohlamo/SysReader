"""
Macro scanning, expression sanitization, and evaluation logic for SysReader parser.
Leverages GCC preprocessor (`gcc -dM -E`), iterative Python expression evaluation,
and an ephemeral C compiler fallback to evaluate complex kernel macros.
"""

import os
import re
import subprocess
import tempfile


def scan_header_with_gcc(header_path):
    """Runs gcc -dM -E on the specified header to retrieve preprocessed macro definitions."""
    if os.path.exists(header_path):
        cmd = ["gcc", "-dM", "-E", header_path]
    elif header_path.startswith("/usr/include/"):
        include_name = header_path[len("/usr/include/"):]
        cmd = ["gcc", "-dM", "-E", "-x", "c", "-include", include_name, "/dev/null"]
    else:
        print(f"[-] Skipping missing header: {header_path}")
        return {}

    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] Error running '{' '.join(cmd)}': {e.stderr.strip()[:100]}")
        return {}

    macros = {}
    for line in res.stdout.splitlines():
        # Match #define NAME VALUE (skip function-like macros #define NAME(...))
        m = re.match(r"^#define\s+([A-Za-z0-9_]+)\s+(.+)$", line)
        if m:
            name, val = m.groups()
            macros[name] = val.strip()

    print(f"[*] Parsed {len(macros):>4} macros from: {header_path}")
    return macros


def scan_all_headers(header_paths):
    """Scans all configured headers using gcc -dM -E and extracts raw macro definitions."""
    print("[*] Gathering macros via 'gcc -dM -E' across host system headers...")
    raw_macros = {}
    for path in header_paths:
        header_macros = scan_header_with_gcc(path)
        raw_macros.update(header_macros)
    print(f"[+] Total collected unique macro definitions: {len(raw_macros)}")
    return raw_macros


def scan_structs(header_paths):
    """Scans header files for struct declarations (e.g. clone_args, open_how)."""
    struct_pattern = re.compile(r"struct\s+([a-zA-Z0-9_]+)\s*\{([^}]+)\};", re.DOTALL)
    field_pattern = re.compile(
        r"^\s*([a-zA-Z0-9_*]+(?:\s+[a-zA-Z0-9_*]+)*)\s+([a-zA-Z0-9_]+)\s*(?:\[\s*\d*\s*\])?\s*;",
        re.MULTILINE,
    )

    discovered_structs = {}
    for path in header_paths:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            continue

        for match in struct_pattern.finditer(content):
            s_name, s_body = match.groups()
            fields = []
            for f_match in field_pattern.finditer(s_body):
                f_type, f_name = f_match.groups()
                fields.append({"name": f_name, "type": f_type.strip()})

            if fields and s_name not in discovered_structs:
                discovered_structs[s_name] = fields

    print(f"[+] Discovered {len(discovered_structs)} C structs from headers ({', '.join(sorted(discovered_structs.keys()))})")
    return discovered_structs


def sanitize_c_expression(expr):
    """Cleans C macro expressions to make them valid Python arithmetic/bitwise expressions."""
    # Strip comments
    expr = re.sub(r"/\*.*?\*/", "", expr)
    expr = re.sub(r"//.*$", "", expr)
    # Strip C-style type casts, e.g. (mode_t), (unsigned long), (__u64)
    expr = re.sub(
        r"\(\s*(?:const\s+)?(?:unsigned\s+|signed\s+)?"
        r"(?:int|long|short|char|mode_t|size_t|loff_t|uint\d+_t|int\d+_t|__u\d+|__s\d+|__aligned_u\d+)\s*\)",
        "",
        expr,
    )
    # Strip integer suffixes, e.g. 1ULL, 0x10UL, 2U, 5L
    expr = re.sub(r"(?i)\b(0x[0-9a-f]+|\d+)[ul]+\b", r"\1", expr)
    # Convert C octals, e.g. 0100 -> 0o100, 00 -> 0o0, but leave 0 and hex intact
    expr = re.sub(r"\b0([0-7]+)\b", r"0o\1", expr)
    return expr.strip()


def evaluate_with_gcc(symbols):
    """Compiles a small C program to evaluate macros/enums that could not be parsed statically."""
    if not symbols:
        return {}

    includes = [
        "#include <stdio.h>",
        "#include <fcntl.h>",
        "#include <sys/mman.h>",
        "#include <sys/socket.h>",
        "#include <sys/mount.h>",
        "#include <linux/sched.h>",
        "#include <poll.h>",
        "#include <signal.h>",
    ]
    body = []
    for s in symbols:
        body.append(f'#ifdef {s}\n    printf("{s}=%llu\\n", (unsigned long long)({s}));\n#endif')

    code = "\n".join(includes) + "\nint main() {\n" + "\n".join(body) + "\n    return 0;\n}\n"

    out = {}
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write(code)
            src_path = f.name
        bin_path = src_path + ".bin"
        p = subprocess.run(["gcc", "-w", "-o", bin_path, src_path],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if p.returncode == 0:
            res = subprocess.run([bin_path], stdout=subprocess.PIPE, text=True, check=True)
            for line in res.stdout.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    out[k] = int(v)
        subprocess.run(["rm", "-f", src_path, bin_path], check=False)
    except Exception:
        pass

    return out


def evaluate_macros(raw_macros, blacklist=None, target_prefixes=None):
    """Iteratively evaluates macro expressions into integer constants."""
    print("[*] Evaluating macro expressions and resolving dependencies...")
    blacklist = blacklist or set()
    evaluated = {}

    # 1. Fast path: Direct integer parsing
    for k, v in raw_macros.items():
        if k in blacklist:
            continue
        try:
            val = int(v, 0)
            evaluated[k] = val
        except (ValueError, SyntaxError):
            pass

    # 2. Iterative evaluation with Python eval
    changed = True
    iterations = 0
    while changed and iterations < 15:
        changed = False
        iterations += 1
        for k, v in raw_macros.items():
            if k in evaluated or k in blacklist:
                continue
            clean_expr = sanitize_c_expression(v)
            try:
                val = eval(clean_expr, {"__builtins__": None}, evaluated)
                if isinstance(val, int):
                    evaluated[k] = val
                    changed = True
            except Exception:
                pass

    # 3. Fallback for unresolved target symbols via GCC
    if target_prefixes:
        needed_symbols = set()
        for sym, raw_val in raw_macros.items():
            if sym not in evaluated and sym not in blacklist:
                if any(sym.startswith(p) for p in target_prefixes):
                    needed_symbols.add(sym)

        if needed_symbols:
            gcc_evaluated = evaluate_with_gcc(list(needed_symbols))
            evaluated.update(gcc_evaluated)

    print(f"[+] Successfully evaluated {len(evaluated)} integer constants!")
    return evaluated


def filter_flags(matched_flags, target_arg_name="", blacklist=None, preferred_names=None):
    """Filters out non-flag helper constants and resolves preferred canonical names."""
    blacklist = blacklist or set()
    preferred_names = preferred_names or {}
    filtered = {}

    for name, val in matched_flags.items():
        if name in blacklist:
            continue
        # Internal glibc/kernel macros starting with double underscore
        if name.startswith("__") and not name.startswith("__W"):
            continue
        # Filter signal names to standard signal range (1..32), unless target arg is 'how' (which uses SIG_BLOCK/UNBLOCK/SETMASK)
        if name.startswith("SIG") and target_arg_name != "how":
            if name.startswith("SIG_") or name.startswith("SIGEV_") or name.startswith("SIGRT"):
                continue
            if val < 1 or val > 32:
                continue
        # If target argument is 'flags', exclude AT_FDCWD (-100) which belongs in dfd
        if target_arg_name == "flags" and name == "AT_FDCWD":
            continue
        # De-duplicate aliases in favor of preferred canonical names
        if name in preferred_names and preferred_names[name] in matched_flags:
            continue
        filtered[name] = val

    return filtered
