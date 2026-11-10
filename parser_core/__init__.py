"""
SysReader Parser Core Package
Provides modular syscall and flag parsing tools leveraging host C headers.
"""

from .builder import SyscallDatabaseBuilder
from .config import DEFAULT_HEADERS, MACRO_BLACKLIST, PREFERRED_NAMES
from .descriptions import FLAG_DESCRIPTIONS
from .routing import PREFIX_ROUTING
from .schemas import get_base_syscall_schemas, SYSCALL_SCHEMAS, FALLBACK_STRUCTS

__all__ = [
    "SyscallDatabaseBuilder",
    "DEFAULT_HEADERS",
    "MACRO_BLACKLIST",
    "PREFERRED_NAMES",
    "FLAG_DESCRIPTIONS",
    "PREFIX_ROUTING",
    "SYSCALL_SCHEMAS",
    "FALLBACK_STRUCTS",
    "get_base_syscall_schemas",
]
